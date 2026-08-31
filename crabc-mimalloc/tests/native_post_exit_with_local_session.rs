use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_reallocate, native_usable_size, prepare_native_later_thread_arena, ticket_zero_allocate,
    ticket_zero_free,
};

#[cfg(feature = "native-runtime-test-audit")]
use crabc_mimalloc::__crabc_runtime::native_runtime_fork_admission_test_audit;

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

    // W01's B-side replacement must copy this exact bounded source prefix
    // before generic pointer-first nonlocal free consumes the aggregate
    // member. The old source address is stale after that successful return.
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
fn native_post_exit_free_keeps_a_preexisting_b_session_continuable() {
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

    #[cfg(feature = "native-runtime-test-audit")]
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "A's completed persistent owner releases its admission before B attaches"
    );

    let (local_sender, local_receiver) = mpsc::sync_channel(0);
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "B's parked local session owns the only admission after A's owner completed"
        );
        let local = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B establishes its own parked local native session"),
        };
        // SAFETY: this exact B-local client remains live in B's private
        // ledger until its later successor-route handoff.
        unsafe {
            local.as_ptr().write(0x71);
            local.as_ptr().add(52).write(0x72);
        }

        // SAFETY: A supplied this exact still-live aggregate address before
        // its typed route detached. This selected post-exit source remains
        // `AbandonedMapped`, so W01 may establish B's persistent target,
        // copy its bounded prefix, and consume the old source without
        // borrowing A's local engine or route.
        let medium = unsafe { core::ptr::NonNull::new_unchecked(detached_clients[2] as *mut u8) };
        assert!(
            unsafe { native_usable_size(medium) }.is_some_and(|usable_size| usable_size >= 64 * 1024),
            "the PageMap pointer query reads A's detached source extent beside B's local session"
        );
        let replacement = match unsafe { native_reallocate(Some(medium), 4096) } {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable => {
                panic!("B finds A's abandoned-mapped source through PageMap facts")
            }
            NativePageAllocationResult::AllocationFailed => {
                panic!("B creates its replacement through its persistent owner")
            }
            NativePageAllocationResult::Retained => {
                panic!("only a true Detached source is retained; this selected source is AbandonedMapped")
            }
        };
        assert_ne!(
            replacement, medium,
            "the nonlocal source cannot use B's local in-place realloc path"
        );
        assert!(
            unsafe { native_usable_size(replacement) }
                .is_some_and(|usable_size| usable_size >= 4096),
            "B's replacement covers its requested extent"
        );
        // SAFETY: successful W01 reallocation copied the bounded 4 KiB prefix
        // before it consumed the old `medium` source. The old address must not
        // be read or freed again after this point.
        assert_eq!(unsafe { replacement.as_ptr().read() }, 0x61);
        assert_eq!(unsafe { replacement.as_ptr().add(4095).read() }, 0x62);
        assert_eq!(
            unsafe { native_free(replacement) },
            NativePageFreeResult::Freed,
            "B releases only its successful local replacement"
        );

        for (index, (address, request)) in detached_clients
            .into_iter()
            .zip(OWNER_EXIT_REQUESTS)
            .enumerate()
        {
            if index == 2 {
                // W01 already consumed A's exact medium source while creating
                // and copying B's replacement above, so it must not be offered
                // to generic pointer-first free a second time.
                continue;
            }
            // SAFETY: A supplied each exact still-live native address before
            // its typed route detached. The route must validate it without
            // disturbing B's independently parked local session.
            let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
            assert!(
                unsafe { native_usable_size(block) }.is_some_and(|usable_size| usable_size >= request),
                "B's parked local session still permits A's PageMap pointer query"
            );
            assert_eq!(
                unsafe { native_free(block) },
                NativePageFreeResult::Freed,
                "B can consume A's exact post-exit client while retaining its own session"
            );
        }
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "source consumption leaves only B's parked local-session admission active before B exits"
        );
        let continued = match native_allocate_aligned(89, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!(
                "B resumes only its own parked session for a new local allocation after A's source consumption"
            ),
        };
        // SAFETY: `continued` is B's exact local client until the local free
        // immediately below. Its contents distinguish this ordinary resumed
        // session operation from A's already consumed source.
        unsafe {
            continued.as_ptr().write(0x73);
            continued.as_ptr().add(88).write(0x74);
        }
        assert_eq!(
            unsafe { continued.as_ptr().read() },
            0x73,
            "the resumed local allocation remains private to B's session"
        );
        assert_eq!(
            unsafe { continued.as_ptr().add(88).read() },
            0x74,
            "the resumed local allocation preserves B's exact extent"
        );
        assert_eq!(
            unsafe { native_free(continued) },
            NativePageFreeResult::Freed,
            "B may return the continued local allocation before its own source finish"
        );

        let successor = match unsafe { native_reallocate(Some(local), 4096) } {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!(
                "B resumes only its own parked session for a local replacement after A's source consumption"
            ),
        };
        assert_eq!(
            unsafe { successor.as_ptr().read() },
            0x71,
            "the continued local replacement preserves B's first sentinel"
        );
        assert_eq!(
            unsafe { successor.as_ptr().add(52).read() },
            0x72,
            "the continued local replacement preserves B's second sentinel"
        );
        local_sender
            .send(successor.as_ptr().addr())
            .expect("B publishes only its continued C-shaped local client before B exits");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B tears down its own live session into a separate typed route after A's source was consumed"
        );
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            0,
            "B's completed persistent owner releases its admission after its own session finishes"
        );
    });
    let local = local_receiver
        .recv()
        .expect("the coordinator receives B's exact local client before B exits");
    releaser
        .join()
        .expect("B completes its local session and publishes its successor route");

    #[cfg(feature = "native-runtime-test-audit")]
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "B's successor route carries no worker-admission claim after B joins"
    );

    let final_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "C owns the only admission beside B's successor route"
        );
        // SAFETY: B detached this exact local address into its own typed
        // native route after B had consumed A's source.
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
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            0,
            "C's normal finish releases its admission after B's terminal route free"
        );
    });
    final_releaser
        .join()
        .expect("C completes B's successor detached-route lifecycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates after C settles B's successor lifecycle claim"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
