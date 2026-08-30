use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_reallocate, native_usable_size, prepare_native_later_thread_arena, ticket_zero_allocate,
    ticket_zero_free,
};

const OWNER_EXIT_CLIENT_COUNT: usize = 6;
const OWNER_EXIT_REQUESTS: [usize; OWNER_EXIT_CLIENT_COUNT] = [
    37,
    1025,
    64 * 1024,
    128 * 1024,
    1024 * 1024,
    7,
];

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_owner_exit_aggregate() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
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

    // The B-side replacement must copy only the pinned overlap while B keeps
    // its own independent session parked. This source client otherwise stays
    // an ordinary aggregate member until the typed detached route consumes it.
    unsafe {
        medium.as_ptr().write(0x61);
        medium.as_ptr().add(4095).write(0x62);
    }

    [
        direct_small.as_ptr().addr(),
        non_direct_small.as_ptr().addr(),
        medium.as_ptr().addr(),
        large.as_ptr().addr(),
        arena_singleton.as_ptr().addr(),
        os_singleton.as_ptr().addr(),
    ]
}

#[test]
fn native_post_exit_free_preserves_a_preexisting_b_session() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the mixed B-session regression"
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
            .expect("A publishes only exact C-shaped route inputs");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A transfers its source-shaped aggregate into the typed route"
        );
    });
    let detached_clients = owner_receiver
        .recv()
        .expect("the coordinator receives A's exact detached-route inputs");
    owner
        .join()
        .expect("A completes its source owner-exit boundary");

    let (local_sender, local_receiver) = mpsc::sync_channel(0);
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let local = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B establishes its own parked local native session"),
        };

        // SAFETY: A supplied this exact still-live aggregate address before
        // its typed route detached. The route must keep its own short access
        // private while B resumes and re-parks only B's independent session
        // for the normal replacement allocation.
        let medium = unsafe { core::ptr::NonNull::new_unchecked(detached_clients[2] as *mut u8) };
        let replacement = match unsafe { native_reallocate(Some(medium), 4096) } {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B replaces A's exact medium client beside its parked local session"),
        };
        assert_ne!(
            replacement, medium,
            "the detached A Theap cannot provide same-page reuse to B"
        );
        assert_eq!(unsafe { replacement.as_ptr().read() }, 0x61);
        assert_eq!(unsafe { replacement.as_ptr().add(4095).read() }, 0x62);
        assert_eq!(
            unsafe { native_free(replacement) },
            NativePageFreeResult::Freed,
            "B releases its normal replacement through its own private ledger"
        );

        for (index, (address, request)) in detached_clients
            .into_iter()
            .zip(OWNER_EXIT_REQUESTS)
            .enumerate()
        {
            if index == 2 {
                // The exact medium client was terminally consumed by the
                // replacement above, so it must not be offered to A's route
                // a second time.
                continue;
            }
            // SAFETY: A supplied each exact still-live native address before
            // its typed route detached. The route must validate it without
            // disturbing B's independently parked local session.
            let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
            assert!(
                unsafe { native_usable_size(block) }.is_some_and(|usable_size| usable_size >= request),
                "B's parked local session still permits A's exact read-only route query"
            );
            assert_eq!(
                unsafe { native_free(block) },
                NativePageFreeResult::Freed,
                "B can consume A's exact post-exit client while retaining its own session"
            );
        }
        local_sender
            .send(local.as_ptr().addr())
            .expect("B publishes only its C-shaped local client before B exits");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B tears down its own live session into a separate typed route before it settles A's proof"
        );
    });
    let local = local_receiver
        .recv()
        .expect("the coordinator receives B's exact local client before B exits");
    releaser
        .join()
        .expect("B completes both its local and detached-route lifecycles");

    let final_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: B detached this exact local address into its own typed
        // native route after B had terminally released A's route.
        let local = unsafe { core::ptr::NonNull::new_unchecked(local as *mut u8) };
        assert_eq!(
            unsafe { native_free(local) },
            NativePageFreeResult::Freed,
            "C can release B's successor route after B's attachment has detached"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "C settles B's typed completion after its own no-page finish"
        );
    });
    final_releaser
        .join()
        .expect("C completes B's successor detached-route lifecycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates after B settles both lifecycle claims"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
