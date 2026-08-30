use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    after_fork_child, after_fork_parent, attach_current_thread, before_fork,
    finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, prepare_native_later_thread_arena,
    process_is_active, ticket_zero_allocate, ticket_zero_free,
};

#[cfg(feature = "native-runtime-test-audit")]
use crabc_mimalloc::__crabc_runtime::native_runtime_fork_admission_test_audit;

// Linux's raw wait4 ABI uses bit zero for WNOHANG. The child is deliberately
// limited to the copied fork boundary: it does not use an inherited route,
// page owner, or allocator before it exits.
const WNOHANG: u32 = 1;
const OWNER_EXIT_CLIENT_COUNT: usize = 6;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn wait_for_disabled_child(pid: i32) {
    let mut status = 0;
    for _ in 0..500 {
        let waited = unsafe {
            crabc_core::process::wait4_raw(pid, &mut status, WNOHANG)
                .expect("the parent polls the terminal-proof fork child")
        };
        if waited == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        assert_eq!(waited, pid, "wait4 returns the exact fork child");
        assert_eq!(status, 0, "the copied runtime disables rather than repairs the live route");
        return;
    }
    let _ = crabc_core::process::kill(pid, 9);
    let _ = unsafe { crabc_core::process::wait4_raw(pid, &mut status, 0) };
    panic!("the terminal-proof fork child exceeded its five-second deadline");
}

fn fork_terminal_proof_child() -> ! {
    after_fork_child(true);
    if process_is_active() || attach_current_thread() != ThreadAttachResult::Inactive {
        crabc_core::process::exit_immediately(101);
    }
    crabc_core::process::exit_immediately(0);
}

fn allocate_owner_exit_aggregate() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let direct_small = match native_allocate_aligned(37, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A allocates its direct-small client"),
    };
    let non_direct_small = match native_allocate_aligned(1025, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A allocates its non-direct-small client"),
    };
    let medium = match native_allocate_aligned(64 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A allocates its medium client"),
    };
    let large = match native_allocate_aligned(128 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A allocates its regular-large client"),
    };
    let arena_singleton = match native_allocate_aligned(1024 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A allocates its arena-singleton client"),
    };
    let os_singleton = match native_allocate_aligned(7, 128 * 1024, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A allocates its OS-singleton client"),
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

fn free_exact_route_client(address: usize) {
    // SAFETY: A supplies this exact detached-route input before it exits. The
    // native registry must prove ownership privately before source free.
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "B consumes only one exact client from A's detached aggregate"
    );
}

#[test]
fn terminal_post_exit_proof_keeps_fork_child_disabled_until_b_finishes() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the terminal-proof fork regression"
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
        "A's detached route keeps its worker-admission claim live before B attaches"
    );

    let (terminal_sender, terminal_receiver) = mpsc::sync_channel(0);
    let (release_sender, release_receiver) = mpsc::sync_channel(0);
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        for address in [clients[5], clients[4], clients[3], clients[2], clients[1], clients[0]] {
            free_exact_route_client(address);
        }
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            2,
            "A's terminal proof and B's live attachment both remain admitted before B finishes"
        );
        terminal_sender
            .send(())
            .expect("B reports the terminal source release before its lifecycle finish");
        release_receiver
            .recv()
            .expect("the initial thread releases B after the fork-child check");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B's normal finish is the only operation that consumes A's terminal proof"
        );
    });

    terminal_receiver
        .recv()
        .expect("B reaches the terminal-proof, pre-finish lifecycle state");
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "ticket zero stays unavailable while B holds A's typed completion"
    );

    before_fork();
    match crabc_core::process::fork_raw() {
        Ok(0) => fork_terminal_proof_child(),
        Ok(pid) => {
            after_fork_parent();
            wait_for_disabled_child(pid);
        }
        Err(error) => {
            after_fork_parent();
            release_sender
                .send(())
                .expect("the parent releases B after the failed fork");
            releaser
                .join()
                .expect("B finishes after the failed fork");
            panic!("the terminal-proof fork succeeds: {error:?}");
        }
    }
    assert!(
        process_is_active(),
        "the parent preserves its active detached route after the conservative child branch"
    );
    release_sender
        .send(())
        .expect("the parent releases B after the disabled child exits");
    releaser
        .join()
        .expect("B consumes the typed completion through its normal finish");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates only after B consumes A's completion"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
