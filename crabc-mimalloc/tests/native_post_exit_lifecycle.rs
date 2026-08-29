use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, native_reallocate, native_usable_size,
    prepare_native_later_thread_arena,
    ticket_zero_allocate, ticket_zero_free, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

#[test]
fn native_post_exit_route_keeps_the_dormant_pair_busy_until_b_finishes() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before its shadow owner-exit witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before a native worker borrows it"
    );

    let (blocks_sender, blocks_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let direct_small = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("owner receives the direct-small native client"),
        };
        let non_direct_small = match native_allocate_aligned(1025, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("owner receives the non-direct-small native client"),
        };
        let medium = match native_allocate_aligned(64 * 1024, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("owner receives the medium native client"),
        };
        let large = match native_allocate_aligned(128 * 1024, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("owner receives the regular-large native client"),
        };
        let arena_singleton = match native_allocate_aligned(1024 * 1024, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("owner receives the arena-singleton native client"),
        };
        let os_singleton = match native_allocate_aligned(7, 128 * 1024, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("owner receives the OS-singleton native client"),
        };
        assert_eq!(
            os_singleton.as_ptr().addr() % (128 * 1024),
            0,
            "the mixed aggregate keeps its OS-singleton alignment before owner exit"
        );
        // A rejected post-exit realloc must preserve this exact original
        // client. The detached route has no B-side Theap that source mimalloc
        // could use for allocate/copy/free.
        unsafe {
            direct_small.as_ptr().write(0x41);
            direct_small.as_ptr().add(36).write(0x42);
            non_direct_small.as_ptr().write(0x43);
            non_direct_small.as_ptr().add(1024).write(0x44);
            medium.as_ptr().write(0x45);
            medium.as_ptr().add(64 * 1024 - 1).write(0x46);
            large.as_ptr().write(0x47);
            large.as_ptr().add(128 * 1024 - 1).write(0x48);
            arena_singleton.as_ptr().write(0x49);
            arena_singleton
                .as_ptr()
                .add(1024 * 1024 - 1)
                .write(0x4a);
            os_singleton.as_ptr().write(0x4b);
            os_singleton.as_ptr().add(6).write(0x4c);
        }
        // The receiver gets only the C-shaped input values that `free` would
        // provide. A's runtime route retains their actual client ownership.
        blocks_sender
            .send((
                direct_small.as_ptr().addr(),
                non_direct_small.as_ptr().addr(),
                medium.as_ptr().addr(),
                large.as_ptr().addr(),
                arena_singleton.as_ptr().addr(),
                os_singleton.as_ptr().addr(),
            ))
            .expect("the fresh B receives each exact mixed-aggregate client address");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A transfers its live aggregate to the typed post-exit route"
        );
    });
    let (direct_small, non_direct_small, medium, large, arena_singleton, os_singleton) = blocks_receiver
        .recv()
        .expect("the owner publishes every mixed-aggregate client before exit");
    owner
        .join()
        .expect("A finishes after the route owns its detached aggregate");

    let (terminal_sender, terminal_receiver) = mpsc::sync_channel(0);
    let release_b = Arc::new(Barrier::new(2));
    let b_release = Arc::clone(&release_b);
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: A has completed its typed detached route, and the test
        // passes each exact C-shaped client to its fresh no-page B consumer.
        let direct_small = unsafe { core::ptr::NonNull::new_unchecked(direct_small as *mut u8) };
        let non_direct_small = unsafe { core::ptr::NonNull::new_unchecked(non_direct_small as *mut u8) };
        let medium = unsafe { core::ptr::NonNull::new_unchecked(medium as *mut u8) };
        let large = unsafe { core::ptr::NonNull::new_unchecked(large as *mut u8) };
        let arena_singleton = unsafe { core::ptr::NonNull::new_unchecked(arena_singleton as *mut u8) };
        let os_singleton = unsafe { core::ptr::NonNull::new_unchecked(os_singleton as *mut u8) };
        assert!(
            unsafe { native_usable_size(direct_small) }.is_some_and(|size| size >= 37),
            "the opaque post-exit route preserves the direct-small usable extent"
        );
        assert!(
            unsafe { native_usable_size(non_direct_small) }.is_some_and(|size| size >= 1025),
            "the opaque post-exit route preserves the non-direct-small usable extent"
        );
        assert!(
            unsafe { native_usable_size(medium) }.is_some_and(|size| size >= 64 * 1024),
            "the opaque post-exit route preserves the exact medium client's usable extent"
        );
        assert!(
            unsafe { native_usable_size(large) }.is_some_and(|size| size >= 128 * 1024),
            "the opaque post-exit route preserves the regular-large usable extent"
        );
        assert!(
            unsafe { native_usable_size(arena_singleton) }.is_some_and(|size| size >= 1024 * 1024),
            "the opaque post-exit route preserves the arena-singleton usable extent"
        );
        assert!(
            unsafe { native_usable_size(os_singleton) }.is_some_and(|size| size >= 7),
            "the opaque post-exit route preserves the OS-singleton usable extent"
        );
        assert!(
            matches!(
                unsafe { native_reallocate(Some(medium), 4096) },
                NativePageAllocationResult::Unavailable
            ),
            "post-exit realloc declines without borrowing a B-side allocator"
        );
        assert_eq!(unsafe { direct_small.as_ptr().read() }, 0x41);
        assert_eq!(unsafe { direct_small.as_ptr().add(36).read() }, 0x42);
        assert_eq!(unsafe { non_direct_small.as_ptr().read() }, 0x43);
        assert_eq!(unsafe { non_direct_small.as_ptr().add(1024).read() }, 0x44);
        assert_eq!(unsafe { medium.as_ptr().read() }, 0x45);
        assert_eq!(unsafe { medium.as_ptr().add(64 * 1024 - 1).read() }, 0x46);
        assert_eq!(unsafe { large.as_ptr().read() }, 0x47);
        assert_eq!(unsafe { large.as_ptr().add(128 * 1024 - 1).read() }, 0x48);
        assert_eq!(unsafe { arena_singleton.as_ptr().read() }, 0x49);
        assert_eq!(unsafe { arena_singleton.as_ptr().add(1024 * 1024 - 1).read() }, 0x4a);
        assert_eq!(unsafe { os_singleton.as_ptr().read() }, 0x4b);
        assert_eq!(unsafe { os_singleton.as_ptr().add(6).read() }, 0x4c);
        assert_eq!(unsafe { native_free(medium) }, NativePageFreeResult::Freed);
        assert_eq!(unsafe { native_free(os_singleton) }, NativePageFreeResult::Freed);
        assert_eq!(unsafe { native_free(arena_singleton) }, NativePageFreeResult::Freed);
        assert_eq!(unsafe { native_free(large) }, NativePageFreeResult::Freed);
        assert_eq!(unsafe { native_free(non_direct_small) }, NativePageFreeResult::Freed);
        assert_eq!(unsafe { native_free(direct_small) }, NativePageFreeResult::Freed);
        assert!(
            matches!(
                native_allocate_aligned(73, 16, false),
                NativePageAllocationResult::Unavailable
            ),
            "B stays a no-page finisher after terminal route release until it consumes A's proof"
        );
        terminal_sender
            .send(())
            .expect("B reports the terminal route free before its own finish");
        b_release.wait();
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B finishes its no-page attachment before releasing A's completion"
        );
    });

    terminal_receiver
        .recv()
        .expect("B reaches the route-terminal, pre-finish state");
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "the dormant pair stays unavailable after route release until B's normal finish"
    );
    release_b.wait();
    releaser
        .join()
        .expect("B completes the typed post-exit lifecycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero resumes only after B finishes"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
