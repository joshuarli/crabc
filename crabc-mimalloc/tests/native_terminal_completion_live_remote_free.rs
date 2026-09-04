use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_runtime_fork_admission_test_audit, prepare_native_later_thread_arena,
    ticket_zero_allocate, ticket_zero_free,
};

const OWNER_EXIT_CLIENT_COUNT: usize = 6;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_owner_exit_aggregate() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let direct_small = match native_allocate_aligned(37, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its direct-small native client"),
    };
    let non_direct_small = match native_allocate_aligned(1025, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its non-direct-small native client"),
    };
    let medium = match native_allocate_aligned(64 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its medium native client"),
    };
    let large = match native_allocate_aligned(128 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its regular-large native client"),
    };
    let arena_singleton = match native_allocate_aligned(1024 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its arena-singleton native client"),
    };
    let os_singleton = match native_allocate_aligned(7, 128 * 1024, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its OS-singleton native client"),
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

fn publish_owner_exit_page_map_sources() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        sender
            .send(allocate_owner_exit_aggregate())
            .expect("A publishes only its exact PageMap source clients before source owner exit");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A's persistent owner completes source owner exit with PageMap-visible clients"
        );
    });
    let clients = receiver
        .recv()
        .expect("the coordinator receives every exact A source client before A exits");
    owner
        .join()
        .expect("A completes its source owner-exit boundary");
    clients
}

fn free_exact_post_exit_client(address: usize) {
    // SAFETY: A supplied this exact C-shaped address before source owner exit.
    // The generic pointer-first dispatcher must recover and consume its
    // PageMap source state without recovering A's former owner.
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "B releases only an exact post-exit PageMap source client"
    );
}

#[test]
fn post_exit_page_map_frees_do_not_block_live_remote_publication() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the post-exit publication witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the persistent initial owner readies the first arena before workers begin"
    );

    let post_exit = publish_owner_exit_page_map_sources();
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "A's persistent source finish releases its admission before C and B attach"
    );
    let (remote_sender, remote_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
    let live_owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let remote = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("C creates one live exact source client"),
        };
        let local = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("C keeps one local client while B publishes its remote free"),
        };
        // SAFETY: both blocks remain in C's persistent owner until its later
        // source finish. B receives only `remote`'s raw C address.
        unsafe {
            remote.as_ptr().write(0x61);
            remote.as_ptr().add(36).write(0x62);
            local.as_ptr().write(0x63);
            local.as_ptr().add(72).write(0x64);
        }
        remote_sender
            .send(remote.as_ptr().addr())
            .expect("B receives only C's exact live client");
        resume_receiver
            .recv()
            .expect("C waits until B completes its foreign pointer operations");
        // SAFETY: C's local client was never offered to a foreign operation.
        // C's source finish below force-collects B's already-published remote
        // client before C releases its pages.
        unsafe {
            assert_eq!(local.as_ptr().read(), 0x63);
            assert_eq!(local.as_ptr().add(72).read(), 0x64);
        }
        assert_eq!(
            unsafe { native_free(local) },
            NativePageFreeResult::Freed,
            "C releases only its own local client before source collection"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "C's source finish collects B's publication and releases C's admission"
        );
    });
    let live_remote = remote_receiver
        .recv()
        .expect("C keeps its live persistent owner while B frees A's post-exit sources");

    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            2,
            "C's live persistent owner and B's attachment are the only admitted workers"
        );
        let local = match native_allocate_aligned(89, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B establishes its independent persistent local owner"),
        };
        for address in post_exit {
            free_exact_post_exit_client(address);
        }
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            2,
            "generic post-exit frees leave C and B as the only admitted workers"
        );

        // SAFETY: C supplied this exact live client and remains in its
        // persistent owner until B completes the generic PageMap publication.
        // The prior post-exit source frees carry neither a C client nor a
        // route/completion capability that can freeze B's local owner.
        let live_remote = unsafe { core::ptr::NonNull::new_unchecked(live_remote as *mut u8) };
        assert_eq!(
            unsafe { native_free(live_remote) },
            NativePageFreeResult::Freed,
            "B publishes C's exact live client after generic post-exit frees"
        );
        assert_eq!(
            unsafe { native_free(local) },
            NativePageFreeResult::Freed,
            "B frees its own local client before its source teardown"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B finishes its own persistent owner after both foreign operations"
        );
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "only C's still-live persistent owner remains admitted after B finishes"
        );
    });
    releaser
        .join()
        .expect("B completes generic post-exit and live-owner pointer operations");

    resume_sender
        .send(())
        .expect("C may complete its source finish after B's pointer operations");
    live_owner
        .join()
        .expect("C collects B's publication and completes its own lifecycle");
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "both persistent worker admissions release at their own source finishes"
    );

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("the persistent initial owner remains usable after both worker finishes"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
