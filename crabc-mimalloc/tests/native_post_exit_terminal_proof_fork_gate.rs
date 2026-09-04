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
// limited to the copied fork boundary: it does not use inherited allocator
// state, a page owner, or an allocator before it exits.
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
                .expect("the parent polls the post-exit fork child")
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
    panic!("the post-exit fork child exceeded its five-second deadline");
}

fn fork_post_exit_child() -> ! {
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

fn free_exact_post_exit_client(address: usize) {
    // SAFETY: A supplies this exact post-exit client before it exits. The
    // generic PageMap dispatcher must prove and consume its abandoned source
    // state without recovering A's former owner.
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "B consumes only one exact client through the generic post-exit dispatcher"
    );
}

#[test]
fn post_exit_page_free_keeps_fork_child_disabled_until_b_finishes() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the post-exit fork regression"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the persistent ticket-zero owner readies its dormant first arena before A begins"
    );

    let (owner_sender, owner_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        owner_sender
            .send(allocate_owner_exit_aggregate())
            .expect("A publishes only exact C-shaped post-exit inputs");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A's persistent owner completes source owner exit for its mixed aggregate"
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
        0,
        "A's persistent owner releases its admission through source owner exit before B attaches"
    );

    let (post_exit_sender, post_exit_receiver) = mpsc::sync_channel(0);
    let (release_sender, release_receiver) = mpsc::sync_channel(0);
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        for address in [clients[5], clients[4], clients[3], clients[2], clients[1], clients[0]] {
            free_exact_post_exit_client(address);
        }
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "B's live attachment remains the sole admission after generic post-exit frees"
        );
        post_exit_sender
            .send(())
            .expect("B reports generic post-exit source release before its lifecycle finish");
        release_receiver
            .recv()
            .expect("the initial thread releases B after the fork-child check");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B's normal finish releases its sole live admission after the generic source frees"
        );
    });

    post_exit_receiver
        .recv()
        .expect("B reaches the post-exit-free, pre-finish lifecycle state");
    let while_b_is_attached = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!(
            "the persistent ticket-zero owner remains independent of B's generic post-exit frees"
        ),
    };
    assert_eq!(
        unsafe { ticket_zero_free(while_b_is_attached) },
        TicketZeroPageFreeResult::Freed,
        "the independent ticket-zero operation returns to its dormant pair before fork"
    );
    #[cfg(feature = "native-runtime-test-audit")]
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        1,
        "B's unfinished attachment remains fork-nonquiescent after ticket zero completes"
    );

    before_fork();
    match crabc_core::process::fork_raw() {
        Ok(0) => fork_post_exit_child(),
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
            panic!("the post-exit fork succeeds: {error:?}");
        }
    }
    assert!(
        process_is_active(),
        "the parent preserves its active process owner after the conservative child branch"
    );
    release_sender
        .send(())
        .expect("the parent releases B after the disabled child exits");
    releaser
        .join()
        .expect("B finishes after its generic post-exit frees");

    #[cfg(feature = "native-runtime-test-audit")]
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "B's normal finish releases the final later-thread admission"
    );

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero remains usable after B's generic post-exit lifecycle"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
