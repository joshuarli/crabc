use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_post_exit_registry_test_audit,
    prepare_native_later_thread_arena, ticket_zero_allocate, ticket_zero_free,
};

const EXITED_OWNER_COUNT: usize = 3;
const OWNER_EXIT_CLIENT_COUNT: usize = 6;
const OWNER_EXIT_EPOCHS: usize = 8;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_persistent_owner_exit_clients() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
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

fn publish_exited_persistent_owner() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // The first native allocation promotes this attached worker into its
        // compiler-TLS persistent source owner. Its exit must abandon live
        // page state rather than install an exact-client route.
        sender
            .send(allocate_persistent_owner_exit_clients())
            .expect(
                "A publishes only its exact native clients before persistent owner exit",
            );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes its persistent owner exit through source abandonment"
        );
    });
    let clients = receiver
        .recv()
        .expect(
            "the coordinator receives A's exact clients before persistent owner exit",
        );
    owner
        .join()
        .expect("A completes its persistent source lifecycle");
    clients
}

fn release_exited_persistent_owner(clients: [usize; OWNER_EXIT_CLIENT_COUNT]) {
    std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        for address in clients {
            // SAFETY: A supplied this exact live native address before its
            // persistent owner exited. B passes it only to pointer-centered
            // post-exit dispatch, which must derive authority from page and
            // process abandonment state without an exact-client registry.
            let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
            assert_eq!(
                unsafe { native_free(block) },
                NativePageFreeResult::Freed,
                "B releases A's exact native client through post-exit page dispatch"
            );
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B finishes independently after its post-exit frees"
        );
    })
    .join()
    .expect("the post-exit consumer completes its independent B lifecycle");
}

fn assert_persistent_post_exit_registry_is_empty() {
    let audit = native_post_exit_registry_test_audit();
    assert_eq!(
        audit.published_entry_count, 0,
        "persistent post-exit operations must not allocate registry metadata"
    );
    assert_eq!(
        audit.live_entry_count, 0,
        "persistent post-exit operations must not leave a live exact-client route"
    );
    assert_eq!(
        audit.retained_entry_count, 0,
        "persistent post-exit operations must not retain a terminal exact-client route"
    );
}

#[test]
fn native_persistent_post_exit_routes_do_not_allocate_registry_entries() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the persistent post-exit witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero prepares its dormant pair before persistent owners begin"
    );
    assert_persistent_post_exit_registry_is_empty();

    for epoch in 0..OWNER_EXIT_EPOCHS {
        let clients: [[usize; OWNER_EXIT_CLIENT_COUNT]; EXITED_OWNER_COUNT] =
            core::array::from_fn(|_| publish_exited_persistent_owner());
        assert_persistent_post_exit_registry_is_empty();

        for owner_clients in clients {
            release_exited_persistent_owner(owner_clients);
            assert_persistent_post_exit_registry_is_empty();
        }

        let resumed = match ticket_zero_allocate(73 + epoch, false) {
            TicketZeroPageAllocationResult::Allocated(block) => block,
            _ => panic!("ticket zero reactivates after every complete epoch"),
        };
        assert_eq!(
            unsafe { ticket_zero_free(resumed) },
            TicketZeroPageFreeResult::Freed,
            "the resumed ticket-zero client returns to the dormant pair"
        );
        assert_persistent_post_exit_registry_is_empty();
    }
}
