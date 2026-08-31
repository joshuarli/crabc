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

fn free_post_exit_client(address: usize) {
    // SAFETY: the test simulates one valid C `free` input after the source
    // owner exited. It passes only the raw C-shaped address: `native_free`
    // must derive its current source state from the PageMap rather than from
    // a former-owner route or client ledger.
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "an attached releaser consumes the exited owner's client through page state"
    );
}

#[test]
fn split_releasers_free_mixed_post_exit_clients_through_page_state() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the split post-exit free regression"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial persistent owner prepares the later-worker source arena"
    );
    #[cfg(feature = "native-runtime-test-audit")]
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the initialized process exposes a quiescent source-state baseline");

    let (owner_sender, owner_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        owner_sender
            .send(allocate_owner_exit_aggregate())
            .expect("A publishes only exact C-shaped post-exit free inputs");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes its source owner-exit boundary before future frees"
        );
    });
    let clients = owner_receiver
        .recv()
        .expect("the coordinator receives A's exact inputs before owner exit");
    owner
        .join()
        .expect("A completes the source owner-exit boundary");

    #[cfg(feature = "native-runtime-test-audit")]
    {
        let after_owner_exit = native_runtime_lifecycle_test_audit()
            .expect("the exited source leaves its live clients PageMap-visible");
        assert!(
            after_owner_exit.page_map_registered_entry_count
                > baseline.page_map_registered_entry_count,
            "A's live clients remain registered for pointer-to-page post-exit dispatch"
        );
    }

    let first_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);

        // Preserve the mixed aggregate's singleton/large release order, then
        // let a separate worker consume the remaining regular-page clients.
        free_post_exit_client(clients[5]);
        free_post_exit_client(clients[4]);
        free_post_exit_client(clients[3]);
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B completes after its nonterminal post-exit frees"
        );
    });
    first_releaser
        .join()
        .expect("B completes its nonterminal post-exit frees");

    // Three A clients remain PageMap-owned after B exits. Ticket zero's
    // independent initial persistent owner may still complete its own local
    // operation without changing those post-exit page states.
    let bookkeeping = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero remains independently usable beside A's post-exit pages"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(bookkeeping) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero returns its private client without changing A's post-exit pages"
    );

    let second_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);

        free_post_exit_client(clients[2]);
        free_post_exit_client(clients[1]);
        free_post_exit_client(clients[0]);
        let continued = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("C starts its independent local owner after its post-exit frees"),
        };
        // SAFETY: this is C's exact local client, distinct from every A
        // client consumed through PageMap-derived post-exit dispatch above.
        unsafe {
            continued.as_ptr().write(0x59);
            continued.as_ptr().add(72).write(0x5a);
            assert_eq!(continued.as_ptr().read(), 0x59);
            assert_eq!(continued.as_ptr().add(72).read(), 0x5a);
        }
        assert_eq!(
            unsafe { native_free(continued) },
            NativePageFreeResult::Freed,
            "C frees its independent local client through its current owner"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "C completes after the remaining post-exit frees and its own local work"
        );
    });
    second_releaser
        .join()
        .expect("C completes the remaining post-exit frees");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero remains usable after every post-exit client is freed"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the final ticket-zero client returns through its independent owner"
    );
    #[cfg(feature = "native-runtime-test-audit")]
    {
        let after = native_runtime_lifecycle_test_audit()
            .expect("every releaser joined before the final source-state audit");
        assert_eq!(
            after.page_map_registered_entry_count,
            baseline.page_map_registered_entry_count,
            "all split post-exit clients release their PageMap registrations"
        );
        assert_eq!(
            after.main_heap_abandoned_page_count,
            baseline.main_heap_abandoned_page_count,
            "no arena abandoned page remains after the final post-exit free"
        );
        assert_eq!(
            after.main_heap_os_abandoned_pages_empty,
            baseline.main_heap_os_abandoned_pages_empty,
            "the OS abandoned-page list returns to its baseline state"
        );
        assert_eq!(
            after.live_thread_count,
            baseline.live_thread_count,
            "A, B, and C leave no later-thread source identity behind"
        );
        assert_eq!(
            after.shared_later_theap_count,
            baseline.shared_later_theap_count,
            "split releasers leave no shared later-Theap residue"
        );
    }
}
