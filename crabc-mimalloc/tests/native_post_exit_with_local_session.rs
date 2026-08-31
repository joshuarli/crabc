use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_reallocate, native_usable_size, prepare_native_later_thread_arena, ticket_zero_allocate,
    ticket_zero_free,
};

#[cfg(feature = "native-runtime-test-audit")]
use crabc_mimalloc::__crabc_runtime::native_runtime_lifecycle_test_audit;

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
fn post_exit_replacement_keeps_a_preexisting_b_session_continuable_through_page_state() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the post-exit B-session regression"
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
            .expect("A publishes only exact C-shaped post-exit inputs");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes its source owner-exit boundary before B's operations"
        );
    });
    let post_exit_clients = owner_receiver
        .recv()
        .expect("the coordinator receives A's exact inputs before owner exit");
    owner
        .join()
        .expect("A completes its source owner-exit boundary");

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

    let (local_sender, local_receiver) = mpsc::sync_channel(0);
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let local = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B establishes its own persistent local native owner"),
        };
        // SAFETY: this exact B-local client remains live through B's later
        // owner-local reallocation below.
        unsafe {
            local.as_ptr().write(0x71);
            local.as_ptr().add(52).write(0x72);
        }

        // SAFETY: A supplied this exact still-live aggregate address before
        // its owner exited. W01 reads its PageMap facts, allocates B's
        // replacement, copies the bounded prefix, then consumes A's source
        // through generic pointer-first free without borrowing A's owner.
        let medium = unsafe { core::ptr::NonNull::new_unchecked(post_exit_clients[2] as *mut u8) };
        assert!(
            unsafe { native_usable_size(medium) }.is_some_and(|usable_size| usable_size >= 64 * 1024),
            "the PageMap pointer query reads A's post-exit source extent beside B's local owner"
        );
        let replacement = match unsafe { native_reallocate(Some(medium), 4096) } {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable => {
                panic!("B finds A's post-exit source through PageMap facts")
            }
            NativePageAllocationResult::AllocationFailed => {
                panic!("B creates the W01 replacement through its persistent owner")
            }
            NativePageAllocationResult::Retained => {
                panic!("the selected post-exit source has a generic W03 continuation")
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
        // SAFETY: successful W01 reallocation copied the bounded 4 KiB
        // prefix before it consumed the old `medium` source. The old address
        // must not be read or freed again after this point.
        assert_eq!(unsafe { replacement.as_ptr().read() }, 0x61);
        assert_eq!(unsafe { replacement.as_ptr().add(4095).read() }, 0x62);
        assert_eq!(
            unsafe { native_free(replacement) },
            NativePageFreeResult::Freed,
            "B releases its current W01 replacement through its own local owner"
        );

        for (index, (address, request)) in post_exit_clients
            .into_iter()
            .zip(OWNER_EXIT_REQUESTS)
            .enumerate()
        {
            if index == 2 {
                // W01 already consumed A's medium source while it created and
                // copied B's replacement above, so it must not be offered to
                // generic pointer-first free a second time.
                continue;
            }
            // SAFETY: A supplied each exact still-live native address before
            // its owner exited. PageMap-derived free must consume it without
            // disturbing B's independently persistent local owner.
            let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
            assert!(
                unsafe { native_usable_size(block) }.is_some_and(|usable_size| usable_size >= request),
                "B's local owner still permits A's PageMap pointer query"
            );
            assert_eq!(
                unsafe { native_free(block) },
                NativePageFreeResult::Freed,
                "B can consume A's exact post-exit client through page state"
            );
        }
        let continued = match native_allocate_aligned(89, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B resumes its own local owner after consuming A's post-exit clients"),
        };
        // SAFETY: `continued` is B's exact local client until the local free
        // immediately below. Its contents distinguish this ordinary resumed
        // owner operation from A's completed post-exit sources.
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
            "B may return its continued local allocation before its own source finish"
        );

        let successor = match unsafe { native_reallocate(Some(local), 4096) } {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B performs a local replacement through its persistent owner"),
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
            "B exits with its own local successor still PageMap-owned"
        );
    });
    let local = local_receiver
        .recv()
        .expect("the coordinator receives B's exact local client before B exits");
    releaser
        .join()
        .expect("B completes its local owner-exit lifecycle");

    #[cfg(feature = "native-runtime-test-audit")]
    {
        let after_b_exit = native_runtime_lifecycle_test_audit()
            .expect("B's live local successor remains PageMap-visible after B exits");
        assert!(
            after_b_exit.page_map_registered_entry_count
                > baseline.page_map_registered_entry_count,
            "B's live local successor remains available for a later pointer-first free"
        );
    }

    // B's post-exit local client is PageMap-owned, while ticket zero remains
    // the initial thread's independent persistent owner. Its local operation
    // neither adopts nor completes B's source state.
    let bookkeeping = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero remains independently usable beside B's post-exit local client"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(bookkeeping) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero returns its private client without changing B's post-exit source state"
    );

    let final_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: B published this exact local address before B exited. Its
        // page state remains the only source authority for C's operation.
        let local = unsafe { core::ptr::NonNull::new_unchecked(local as *mut u8) };
        assert!(
            unsafe { native_usable_size(local) }.is_some_and(|usable_size| usable_size >= 4096),
            "C reads B's post-exit local extent through PageMap facts"
        );
        assert_eq!(
            unsafe { native_free(local) },
            NativePageFreeResult::Freed,
            "C consumes B's post-exit local client through generic pointer-first free"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "C completes after its generic post-exit free"
        );
    });
    final_releaser
        .join()
        .expect("C completes B's post-exit local free");

    #[cfg(feature = "native-runtime-test-audit")]
    {
        let after = native_runtime_lifecycle_test_audit()
            .expect("every owner and releaser joined before the final source-state audit");
        assert_eq!(
            after.page_map_registered_entry_count,
            baseline.page_map_registered_entry_count,
            "A's sources and B's local successor release their PageMap registrations"
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
            "post-exit frees leave no shared later-Theap residue"
        );
    }
}
